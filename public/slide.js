const slides=document.querySelectorAll(".slide");

var counter=0;

slides.forEach(
    (slide,index)=>{
        slide.style.left=`${index*100}%`;
    }
)
const slideImage=()=>{
    slides.forEach(
        (slide)=>{
            slide.style.transform=`translateX(-${counter*100}%)`;
        }
    )
}

const goPrev=()=>{
    if(counter>0)counter--;
    else{
        counter=slides.length-1;
    }
    slideImage();
}

const goNext=()=>{
    if(counter<slides.length-1)counter++;
    else{
        counter=0;
    }
    slideImage();
}